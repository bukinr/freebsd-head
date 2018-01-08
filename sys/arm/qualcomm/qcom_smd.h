void qcom_smd_send(void *data, size_t len);

#define QCOM_SMD_RPM_ACTIVE_STATE        0
#define QCOM_SMD_RPM_SLEEP_STATE         1

#define RPM_SERVICE_TYPE_REQUEST        0x00716572 /* "req\0" */
#define RPM_MSG_TYPE_ERR                0x00727265 /* "err\0" */
#define RPM_MSG_TYPE_MSG_ID             0x2367736d /* "msg#" */

