#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/log_stdout.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>

static volatile UA_Boolean running = true;

static void stopHandler(int sig) {
    (void)sig;
    running = false;
}

typedef struct {
    UA_Double line1_conveyor_speed_mpm;
    UA_Double station1_motor_rpm;
    UA_UInt32 robot_arm_3_cycle_count;
    UA_Double line1_vibration_mm_s;
    UA_UInt32 station1_part_count;

    UA_Double weld_cell_temperature_c;
    UA_Double weld_arc_voltage_v;
    UA_Double weld_wire_feed_speed_mmin;
    UA_UInt32 station2_fault_count;

    UA_Double packaging_rate_units_min;
    UA_Double pkg_seal_temp_c;
    UA_UInt32 pkg_reject_count;

    UA_Double air_pressure_bar;
    UA_Double plant_power_kw;
    UA_Double cooling_water_temp_c;

    UA_Boolean line_running;
    UA_Boolean packaging_running;
    UA_Boolean welding_active;
    UA_Boolean maintenance_pause;
    UA_Boolean station2_fault_active;
    UA_Boolean packaging_jam_active;
    UA_Boolean compressor_on;
    UA_UInt32 tick;
    UA_UInt32 pause_remaining;
    UA_UInt32 weld_hold_remaining;
    UA_UInt32 micro_stop_remaining;
    UA_UInt32 packaging_jam_remaining;
    UA_UInt32 wip_buffer;
    UA_Double tool_wear_index;
    UA_Double ambient_temp_c;

    UA_NodeId line1_conveyor_speed_mpm_node;
    UA_NodeId station1_motor_rpm_node;
    UA_NodeId robot_arm_3_cycle_count_node;
    UA_NodeId line1_vibration_mm_s_node;
    UA_NodeId station1_part_count_node;
    UA_NodeId weld_cell_temperature_c_node;
    UA_NodeId weld_arc_voltage_v_node;
    UA_NodeId weld_wire_feed_speed_mmin_node;
    UA_NodeId station2_fault_count_node;
    UA_NodeId packaging_rate_units_min_node;
    UA_NodeId pkg_seal_temp_c_node;
    UA_NodeId pkg_reject_count_node;
    UA_NodeId air_pressure_bar_node;
    UA_NodeId plant_power_kw_node;
    UA_NodeId cooling_water_temp_c_node;
} ProcessModel;

static UA_Double clampDouble(UA_Double value, UA_Double min, UA_Double max) {
    if(value < min)
        return min;
    if(value > max)
        return max;
    return value;
}

static UA_Double approach(UA_Double current, UA_Double target, UA_Double factor) {
    return current + (target - current) * factor;
}

static UA_Double cycleWave(UA_UInt32 tick, UA_UInt32 period, UA_Double amplitude) {
    if(period == 0U)
        return 0.0;
    UA_UInt32 phase = tick % period;
    UA_Double normalized = (UA_Double)phase / (UA_Double)period;
    if(normalized < 0.5)
        return amplitude * (normalized * 4.0 - 1.0);
    return amplitude * (3.0 - normalized * 4.0);
}

static UA_StatusCode addDoubleVariable(UA_Server *server,
                                       UA_UInt16 nsidx,
                                       const char *name,
                                       UA_Double initialValue,
                                       const UA_NodeId *parentNode,
                                       UA_NodeId *outNodeId) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)(uintptr_t)name);
    attr.description = UA_LOCALIZEDTEXT("en-US", (char *)(uintptr_t)name);
    attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    return UA_Server_addVariableNode(server,
                                     UA_NODEID_STRING(nsidx, (char *)(uintptr_t)name),
                                     *parentNode,
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                     UA_QUALIFIEDNAME(nsidx, (char *)(uintptr_t)name),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                     attr,
                                     NULL,
                                     outNodeId);
}

static UA_StatusCode addUInt32Variable(UA_Server *server,
                                       UA_UInt16 nsidx,
                                       const char *name,
                                       UA_UInt32 initialValue,
                                       const UA_NodeId *parentNode,
                                       UA_NodeId *outNodeId) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &initialValue, &UA_TYPES[UA_TYPES_UINT32]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)(uintptr_t)name);
    attr.description = UA_LOCALIZEDTEXT("en-US", (char *)(uintptr_t)name);
    attr.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    return UA_Server_addVariableNode(server,
                                     UA_NODEID_STRING(nsidx, (char *)(uintptr_t)name),
                                     *parentNode,
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                     UA_QUALIFIEDNAME(nsidx, (char *)(uintptr_t)name),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                                     attr,
                                     NULL,
                                     outNodeId);
}

static void writeDouble(UA_Server *server, const UA_NodeId *nodeId, UA_Double value) {
    UA_Variant variant;
    UA_Variant_init(&variant);
    UA_Variant_setScalar(&variant, &value, &UA_TYPES[UA_TYPES_DOUBLE]);
    UA_Server_writeValue(server, *nodeId, variant);
}

static void writeUInt32(UA_Server *server, const UA_NodeId *nodeId, UA_UInt32 value) {
    UA_Variant variant;
    UA_Variant_init(&variant);
    UA_Variant_setScalar(&variant, &value, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Server_writeValue(server, *nodeId, variant);
}

static void updateProcessModel(UA_Server *server, void *data) {
    ProcessModel *m = (ProcessModel *)data;
    m->tick++;

    {
        UA_UInt32 shift_tick = m->tick % 3600U;
        UA_Double shift_load = 1.0;
        UA_Double wear_effect = m->tool_wear_index * 0.9;

        if(shift_tick < 900U) {
            shift_load = 0.88;
        } else if(shift_tick < 2400U) {
            shift_load = 1.06;
        } else if(shift_tick < 3200U) {
            shift_load = 0.96;
        } else {
            shift_load = 0.82;
        }

        if(m->pause_remaining > 0U) {
            m->pause_remaining--;
            m->maintenance_pause = true;
            m->line_running = false;
        } else {
            m->maintenance_pause = true;
            if((m->tick % 1200U) == 0U) {
                m->pause_remaining = 35U;
                m->line_running = false;
            } else {
                m->maintenance_pause = false;
            }
        }

        if(m->micro_stop_remaining > 0U) {
            m->micro_stop_remaining--;
            m->line_running = false;
        } else if(!m->maintenance_pause && (m->tick % 260U) == 0U) {
            m->micro_stop_remaining = 6U;
            m->line_running = false;
        }

        if((m->tick % 95U) == 0U) {
            UA_Double fault_bias = m->line1_vibration_mm_s + wear_effect;
            if(fault_bias > 0.26 || (rand() % 100) < 30) {
                m->station2_fault_active = true;
                m->station2_fault_count += 1U;
            }
        } else if((m->tick % 95U) == 7U) {
            m->station2_fault_active = false;
        }

        if(!m->maintenance_pause && m->micro_stop_remaining == 0U) {
            m->line_running = true;
        }

        if(m->line_running) {
            UA_Double speed_target = 20.0 * shift_load + cycleWave(m->tick, 32U, 1.5) + cycleWave(m->tick, 11U, 0.35);
            if(m->station2_fault_active)
                speed_target -= 2.5;
            speed_target -= wear_effect;
            if(m->wip_buffer > 60U)
                speed_target -= 0.8;
            m->line1_conveyor_speed_mpm = approach(m->line1_conveyor_speed_mpm, speed_target, 0.28);
            m->line1_conveyor_speed_mpm = clampDouble(m->line1_conveyor_speed_mpm, 12.5, 24.0);
        } else {
            m->line1_conveyor_speed_mpm = approach(m->line1_conveyor_speed_mpm, 0.0, 0.62);
            if(m->line1_conveyor_speed_mpm < 0.05)
                m->line1_conveyor_speed_mpm = 0.0;
        }

        m->station1_motor_rpm = 74.0 * m->line1_conveyor_speed_mpm + 8.0 + cycleWave(m->tick, 18U, 8.0);
        m->station1_motor_rpm += m->line1_conveyor_speed_mpm * wear_effect * 0.9;
        m->station1_motor_rpm = clampDouble(m->station1_motor_rpm, 0.0, 1520.0);

        {
            UA_UInt32 incoming_parts = 0U;
            UA_UInt32 outgoing_parts = 0U;

            if(m->line_running) {
                incoming_parts = (m->line1_conveyor_speed_mpm >= 19.5) ? 3U : 2U;
                m->station1_part_count += incoming_parts;
                m->robot_arm_3_cycle_count += (incoming_parts >= 3U) ? 2U : 1U;
                m->tool_wear_index = clampDouble(m->tool_wear_index + 0.00045, 0.0, 1.0);
            } else {
                m->tool_wear_index = clampDouble(m->tool_wear_index - 0.00015, 0.0, 1.0);
            }

            m->wip_buffer += incoming_parts;

            if((m->tick % 310U) == 0U && m->wip_buffer > 45U) {
                m->packaging_jam_active = true;
                m->packaging_jam_remaining = 12U;
            }
            if(m->packaging_jam_remaining > 0U) {
                m->packaging_jam_remaining--;
                m->packaging_jam_active = true;
            } else {
                m->packaging_jam_active = false;
            }

            m->packaging_running = m->line_running && !m->packaging_jam_active;
            if(m->packaging_running) {
                UA_Double packaging_target = 44.5 + cycleWave(m->tick, 28U, 2.5);
                if(m->line1_conveyor_speed_mpm < 18.0)
                    packaging_target -= 4.0;
                if(m->wip_buffer < 10U)
                    packaging_target -= 3.0;
                m->packaging_rate_units_min = approach(m->packaging_rate_units_min, packaging_target, 0.24);
                m->packaging_rate_units_min = clampDouble(m->packaging_rate_units_min, 0.0, 60.0);

                outgoing_parts = (m->packaging_rate_units_min > 47.0) ? 4U : ((m->packaging_rate_units_min > 39.0) ? 3U : 2U);
                if(outgoing_parts > m->wip_buffer)
                    outgoing_parts = m->wip_buffer;
                m->wip_buffer -= outgoing_parts;
            } else {
                m->packaging_rate_units_min = approach(m->packaging_rate_units_min, 0.0, 0.55);
                if(m->packaging_rate_units_min < 0.05)
                    m->packaging_rate_units_min = 0.0;
            }

            if(m->wip_buffer > 120U)
                m->wip_buffer = 120U;
        }

        m->line1_vibration_mm_s = 0.08 + (m->line1_conveyor_speed_mpm / 20.0) * 0.08 + cycleWave(m->tick, 9U, 0.014);
        m->line1_vibration_mm_s += m->tool_wear_index * 0.06;
        if(m->station2_fault_active)
            m->line1_vibration_mm_s += 0.12;
        m->line1_vibration_mm_s = clampDouble(m->line1_vibration_mm_s, 0.03, 0.60);

        if(m->line_running || m->weld_hold_remaining > 0U) {
            if(!m->line_running && m->weld_hold_remaining > 0U)
                m->weld_hold_remaining--;
            if(m->line_running)
                m->weld_hold_remaining = 5U;
            m->welding_active = !m->station2_fault_active;
        } else {
            m->welding_active = false;
        }

        if(m->welding_active) {
            UA_Double weld_temp_target = 71.5 + cycleWave(m->tick, 36U, 3.3) + m->tool_wear_index * 2.0;
            m->weld_cell_temperature_c = approach(m->weld_cell_temperature_c, weld_temp_target, 0.15);
            m->weld_arc_voltage_v = approach(m->weld_arc_voltage_v, 24.7 + cycleWave(m->tick, 8U, 0.85), 0.28);
            m->weld_wire_feed_speed_mmin = approach(m->weld_wire_feed_speed_mmin, 5.0 + cycleWave(m->tick, 14U, 0.20), 0.24);
        } else {
            m->weld_cell_temperature_c = approach(m->weld_cell_temperature_c, m->ambient_temp_c + 4.0, 0.08);
            m->weld_arc_voltage_v = approach(m->weld_arc_voltage_v, 0.0, 0.65);
            if(m->weld_arc_voltage_v < 0.05)
                m->weld_arc_voltage_v = 0.0;
            m->weld_wire_feed_speed_mmin = approach(m->weld_wire_feed_speed_mmin, 0.0, 0.55);
            if(m->weld_wire_feed_speed_mmin < 0.02)
                m->weld_wire_feed_speed_mmin = 0.0;
        }
        m->weld_cell_temperature_c = clampDouble(m->weld_cell_temperature_c, 38.0, 84.0);
        m->weld_arc_voltage_v = clampDouble(m->weld_arc_voltage_v, 0.0, 28.5);
        m->weld_wire_feed_speed_mmin = clampDouble(m->weld_wire_feed_speed_mmin, 0.0, 6.2);

        if(m->packaging_running) {
            m->pkg_seal_temp_c = approach(m->pkg_seal_temp_c, 181.2 + cycleWave(m->tick, 20U, 1.4), 0.17);
        } else {
            m->pkg_seal_temp_c = approach(m->pkg_seal_temp_c, 165.5, 0.07);
        }
        m->pkg_seal_temp_c = clampDouble(m->pkg_seal_temp_c, 160.0, 190.0);

        {
            UA_Double reject_risk = 0.0;
            UA_Double seal_dev = m->pkg_seal_temp_c - 181.0;
            if(seal_dev < 0.0)
                seal_dev = -seal_dev;
            if(seal_dev > 2.2)
                reject_risk += 0.030;
            if(m->station2_fault_active)
                reject_risk += 0.020;
            if(m->line1_vibration_mm_s > 0.23)
                reject_risk += 0.015;
            if(m->packaging_jam_active)
                reject_risk += 0.020;
            if(reject_risk > 0.08)
                reject_risk = 0.08;
            if((rand() % 1000) < (UA_UInt32)(reject_risk * 1000.0))
                m->pkg_reject_count += 1U;
        }

        {
            UA_Double pneumatic_demand = 0.42;
            if(m->line_running)
                pneumatic_demand += 0.30;
            if(m->packaging_running)
                pneumatic_demand += 0.18;
            if(m->station2_fault_active)
                pneumatic_demand += 0.06;

            m->air_pressure_bar -= pneumatic_demand * 0.010;
            if(m->compressor_on)
                m->air_pressure_bar += 0.046;

            if(m->air_pressure_bar < 5.82)
                m->compressor_on = true;
            if(m->air_pressure_bar > 6.22)
                m->compressor_on = false;

            m->air_pressure_bar += cycleWave(m->tick, 12U, 0.012);
            m->air_pressure_bar = clampDouble(m->air_pressure_bar, 5.5, 6.5);

            {
                UA_Double utilization = m->line1_conveyor_speed_mpm / 20.0;
                UA_Double power_target = 98.0;
                if(m->line_running)
                    power_target += 52.0 + utilization * 36.0;
                if(m->welding_active)
                    power_target += 22.0;
                if(m->packaging_running)
                    power_target += 11.0;
                if(m->compressor_on)
                    power_target += 9.0;
                if(m->packaging_jam_active)
                    power_target += 3.0;
                if(m->station2_fault_active)
                    power_target += 5.0;
                power_target += cycleWave(m->tick, 16U, 4.0);
                m->plant_power_kw = approach(m->plant_power_kw, power_target, 0.17);
                m->plant_power_kw = clampDouble(m->plant_power_kw, 90.0, 255.0);
            }

            m->ambient_temp_c = 22.0 + cycleWave(m->tick, 900U, 0.8);
            {
                UA_Double cooling_target = m->ambient_temp_c - 0.8 + (m->plant_power_kw - 110.0) / 30.0;
                if(m->welding_active)
                    cooling_target += 0.8;
                m->cooling_water_temp_c = approach(m->cooling_water_temp_c, cooling_target, 0.11);
                m->cooling_water_temp_c = clampDouble(m->cooling_water_temp_c, 17.5, 30.0);
            }
        }
    }

    writeDouble(server, &m->line1_conveyor_speed_mpm_node, m->line1_conveyor_speed_mpm);
    writeDouble(server, &m->station1_motor_rpm_node, m->station1_motor_rpm);
    writeUInt32(server, &m->robot_arm_3_cycle_count_node, m->robot_arm_3_cycle_count);
    writeDouble(server, &m->line1_vibration_mm_s_node, m->line1_vibration_mm_s);
    writeUInt32(server, &m->station1_part_count_node, m->station1_part_count);
    writeDouble(server, &m->weld_cell_temperature_c_node, m->weld_cell_temperature_c);
    writeDouble(server, &m->weld_arc_voltage_v_node, m->weld_arc_voltage_v);
    writeDouble(server, &m->weld_wire_feed_speed_mmin_node, m->weld_wire_feed_speed_mmin);
    writeUInt32(server, &m->station2_fault_count_node, m->station2_fault_count);
    writeDouble(server, &m->packaging_rate_units_min_node, m->packaging_rate_units_min);
    writeDouble(server, &m->pkg_seal_temp_c_node, m->pkg_seal_temp_c);
    writeUInt32(server, &m->pkg_reject_count_node, m->pkg_reject_count);
    writeDouble(server, &m->air_pressure_bar_node, m->air_pressure_bar);
    writeDouble(server, &m->plant_power_kw_node, m->plant_power_kw);
    writeDouble(server, &m->cooling_water_temp_c_node, m->cooling_water_temp_c);
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    srand((unsigned int)time(NULL));

    UA_Server *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    UA_UInt16 nsidx = (UA_UInt16)UA_Server_addNamespace(server, "http://manufacturing.example/opcua");

    ProcessModel model = {
        .line1_conveyor_speed_mpm = 20.0,
        .station1_motor_rpm = 1485.0,
        .robot_arm_3_cycle_count = 5000U,
        .line1_vibration_mm_s = 0.14,
        .station1_part_count = 200U,
        .weld_cell_temperature_c = 71.0,
        .weld_arc_voltage_v = 24.9,
        .weld_wire_feed_speed_mmin = 5.0,
        .station2_fault_count = 0U,
        .packaging_rate_units_min = 46.0,
        .pkg_seal_temp_c = 181.0,
        .pkg_reject_count = 0U,
        .air_pressure_bar = 6.0,
        .plant_power_kw = 202.0,
        .cooling_water_temp_c = 21.0,
        .line_running = true,
        .packaging_running = true,
        .welding_active = true,
        .maintenance_pause = false,
        .station2_fault_active = false,
        .tick = 0U,
        .pause_remaining = 0U,
        .weld_hold_remaining = 0U,
        .line1_conveyor_speed_mpm_node = UA_NODEID_NULL,
        .station1_motor_rpm_node = UA_NODEID_NULL,
        .robot_arm_3_cycle_count_node = UA_NODEID_NULL,
        .line1_vibration_mm_s_node = UA_NODEID_NULL,
        .station1_part_count_node = UA_NODEID_NULL,
        .weld_cell_temperature_c_node = UA_NODEID_NULL,
        .weld_arc_voltage_v_node = UA_NODEID_NULL,
        .weld_wire_feed_speed_mmin_node = UA_NODEID_NULL,
        .station2_fault_count_node = UA_NODEID_NULL,
        .packaging_rate_units_min_node = UA_NODEID_NULL,
        .pkg_seal_temp_c_node = UA_NODEID_NULL,
        .pkg_reject_count_node = UA_NODEID_NULL,
        .air_pressure_bar_node = UA_NODEID_NULL,
        .plant_power_kw_node = UA_NODEID_NULL,
        .cooling_water_temp_c_node = UA_NODEID_NULL
    };

    UA_ObjectAttributes assemblyAttr = UA_ObjectAttributes_default;
    assemblyAttr.displayName = UA_LOCALIZEDTEXT("en-US", "AssemblyLine");
    assemblyAttr.description = UA_LOCALIZEDTEXT("en-US", "Manufacturing assembly line telemetry model");

    UA_NodeId assemblyLineNode = UA_NODEID_STRING(nsidx, "AssemblyLine");
    UA_StatusCode retval = UA_Server_addObjectNode(server,
                                                   assemblyLineNode,
                                                   UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                                   UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                                                   UA_QUALIFIEDNAME(nsidx, "AssemblyLine"),
                                                   UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                                                   assemblyAttr,
                                                   NULL,
                                                   NULL);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    retval = addDoubleVariable(server, nsidx, "line1_conveyor_speed_mpm", model.line1_conveyor_speed_mpm, &assemblyLineNode, &model.line1_conveyor_speed_mpm_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "station1_motor_rpm", model.station1_motor_rpm, &assemblyLineNode, &model.station1_motor_rpm_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addUInt32Variable(server, nsidx, "robot_arm_3_cycle_count", model.robot_arm_3_cycle_count, &assemblyLineNode, &model.robot_arm_3_cycle_count_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "line1_vibration_mm_s", model.line1_vibration_mm_s, &assemblyLineNode, &model.line1_vibration_mm_s_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addUInt32Variable(server, nsidx, "station1_part_count", model.station1_part_count, &assemblyLineNode, &model.station1_part_count_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "weld_cell_temperature_c", model.weld_cell_temperature_c, &assemblyLineNode, &model.weld_cell_temperature_c_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "weld_arc_voltage_v", model.weld_arc_voltage_v, &assemblyLineNode, &model.weld_arc_voltage_v_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "weld_wire_feed_speed_mmin", model.weld_wire_feed_speed_mmin, &assemblyLineNode, &model.weld_wire_feed_speed_mmin_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addUInt32Variable(server, nsidx, "station2_fault_count", model.station2_fault_count, &assemblyLineNode, &model.station2_fault_count_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "packaging_rate_units_min", model.packaging_rate_units_min, &assemblyLineNode, &model.packaging_rate_units_min_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "pkg_seal_temp_c", model.pkg_seal_temp_c, &assemblyLineNode, &model.pkg_seal_temp_c_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addUInt32Variable(server, nsidx, "pkg_reject_count", model.pkg_reject_count, &assemblyLineNode, &model.pkg_reject_count_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "air_pressure_bar", model.air_pressure_bar, &assemblyLineNode, &model.air_pressure_bar_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "plant_power_kw", model.plant_power_kw, &assemblyLineNode, &model.plant_power_kw_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;
    retval = addDoubleVariable(server, nsidx, "cooling_water_temp_c", model.cooling_water_temp_c, &assemblyLineNode, &model.cooling_water_temp_c_node);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    {
        UA_UInt64 callbackId = 0U;
        retval = UA_Server_addRepeatedCallback(server, updateProcessModel, &model, 1000.0, &callbackId);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    retval = UA_Server_run(server, &running);

cleanup:
    UA_Server_delete(server);
    return (int)retval;
}
