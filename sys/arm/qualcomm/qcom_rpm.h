void qcom_rpm_smd_write(int state, uint32_t type, uint32_t id, void *buf, size_t count);

/*
 * Constants used for addressing resources in the RPM.
 */
#define QCOM_SMD_RPM_BOOST      0x61747362
#define QCOM_SMD_RPM_BUS_CLK    0x316b6c63
#define QCOM_SMD_RPM_BUS_MASTER 0x73616d62
#define QCOM_SMD_RPM_BUS_SLAVE  0x766c7362
#define QCOM_SMD_RPM_CLK_BUF_A  0x616B6C63
#define QCOM_SMD_RPM_LDOA       0x616f646c
#define QCOM_SMD_RPM_LDOB       0x626F646C
#define QCOM_SMD_RPM_MEM_CLK    0x326b6c63
#define QCOM_SMD_RPM_MISC_CLK   0x306b6c63
#define QCOM_SMD_RPM_NCPA       0x6170636E
#define QCOM_SMD_RPM_NCPB       0x6270636E
#define QCOM_SMD_RPM_OCMEM_PWR  0x706d636f
#define QCOM_SMD_RPM_QPIC_CLK   0x63697071
#define QCOM_SMD_RPM_SMPA       0x61706d73
#define QCOM_SMD_RPM_SMPB       0x62706d73
#define QCOM_SMD_RPM_SPDM       0x63707362
#define QCOM_SMD_RPM_VSA        0x00617376
#define QCOM_SMD_RPM_MMAXI_CLK  0x69786d6d
#define QCOM_SMD_RPM_IPA_CLK    0x617069
#define QCOM_SMD_RPM_CE_CLK     0x6563
#define QCOM_SMD_RPM_AGGR_CLK   0x72676761

#define QCOM_RPM_KEY_SOFTWARE_ENABLE                    0x6e657773
#define QCOM_RPM_KEY_PIN_CTRL_CLK_BUFFER_ENABLE_KEY     0x62636370
#define QCOM_RPM_SMD_KEY_RATE                           0x007a484b
#define QCOM_RPM_SMD_KEY_ENABLE                         0x62616e45
#define QCOM_RPM_SMD_KEY_STATE                          0x54415453
#define QCOM_RPM_SCALING_ENABLE_ID                      0x2
