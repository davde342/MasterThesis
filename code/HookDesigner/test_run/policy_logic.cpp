struct DataPoint {
    int id;
    double value;
};

inline bool operator==(const DataPoint& a, const DataPoint& b) {
    return a.id == b.id && a.value == b.value;
}

inline std::ostream& operator<<(std::ostream& os, const DataPoint& dp) {
    os << "{id: " << dp.id << ", value: " << dp.value << "}";
    return os;
}

// @signatures-start
int ParseProprietaryPacket(void* packetBuffer, double complexityWeight);
int ParseProprietaryPacket2(void* packetBuffer, double complexityWeight);
void LogTaskResult(int taskId, const char* status, double result);
int ProcessCommandSignal(int cmdId, double* payloadValue, char* responseBuffer);
int UpdateSensor(int id, double val);
int CalibrateDevice(int id, double val);
int ProcessDataPoint(DataPoint* dp);
void WINAPI PerformCriticalTask(int taskID);
int ProcessNestedSignal(double** ppValue);
// @signatures-end

 
// @GenericEnterLog-start
void GenericEnterLog() {
    std::ostringstream ss;
    ss << "[HOOK LOG] GenericEnterLog invoked!" << std::endl;
    std::cout << ss.str();
}

// @SharedPacketPreHook-start
void SharedPacketPreHook(double& complexityWeight) {
    if (complexityWeight > 500.0) {
        complexityWeight = 100.0;
    }
}
 
// @ProcessCommandSignal_pre-start
void ProcessCommandSignal_pre(double*& payloadValue) {
    if (payloadValue && *payloadValue > 1000.0) {
        *payloadValue = 999.0;
    }
}
 
// @ProcessCommandSignal_post-start
void ProcessCommandSignal_post(int& result, char*& responseBuffer) {
    if (result == 200) {
        result = 403;
        strcpy_s(responseBuffer, 100, "BLOCKED_BY_POLICY");
    }
}

// @SharedDoubleAction_pre-start
void SharedDoubleAction_pre(double& val) {
    val = val * 2.0;
}

// @ProcessDataPoint_pre-start
void ProcessDataPoint_pre(DataPoint*& dp) {
    if (dp) {
        dp->value = dp->value + 100.0;
    }
}

// @PerformCriticalTask_pre-start
void PerformCriticalTask_pre(int& taskID) {
    taskID = taskID + 500;
}

// @LogTaskResult_post-start
void LogTaskResult_post(int& taskId) {
    taskId = taskId + 10000;
}
