#define	FUNNEL_FUNCTL		0x000 /* Funnel Control Register */
#define	 FUNCTL_HOLDTIME_SHIFT	8
#define	 FUNCTL_HOLDTIME_MASK	(0xf << FUNCTL_HOLDTIME_SHIFT)
#define	FUNNEL_PRICTL		0x004 /* Priority Control Register */
#define	FUNNEL_ITATBDATA0	0xEEC /* Integration Register, ITATBDATA0 */
#define	FUNNEL_ITATBCTR2	0xEF0 /* Integration Register, ITATBCTR2 */
#define	FUNNEL_ITATBCTR1	0xEF4 /* Integration Register, ITATBCTR1 */
#define	FUNNEL_ITATBCTR0	0xEF8 /* Integration Register, ITATBCTR0 */
#define	FUNNEL_IMCR		0xF00 /* Integration Mode Control Register */
#define	FUNNEL_CTSR		0xFA0 /* Claim Tag Set Register */
#define	FUNNEL_CTCR		0xFA4 /* Claim Tag Clear Register */
#define	FUNNEL_LOCKACCESS	0xFB0 /* Lock Access */
#define	FUNNEL_LOCKSTATUS	0xFB4 /* Lock Status */
#define	FUNNEL_AUTHSTATUS	0xFB8 /* Authentication status */
#define	FUNNEL_DEVICEID		0xFC8 /* Device ID */
#define	FUNNEL_DEVICETYPE	0xFCC /* Device Type Identifier */
#define	FUNNEL_PERIPH4		0xFD0 /* Peripheral ID4 */
#define	FUNNEL_PERIPH5		0xFD4 /* Peripheral ID5 */
#define	FUNNEL_PERIPH6		0xFD8 /* Peripheral ID6 */
#define	FUNNEL_PERIPH7		0xFDC /* Peripheral ID7 */
#define	FUNNEL_PERIPH0		0xFE0 /* Peripheral ID0 */
#define	FUNNEL_PERIPH1		0xFE4 /* Peripheral ID1 */
#define	FUNNEL_PERIPH2		0xFE8 /* Peripheral ID2 */
#define	FUNNEL_PERIPH3		0xFEC /* Peripheral ID3 */
#define	FUNNEL_COMP0		0xFF0 /* Component ID0 */
#define	FUNNEL_COMP1		0xFF4 /* Component ID1 */
#define	FUNNEL_COMP2		0xFF8 /* Component ID2 */
#define	FUNNEL_COMP3		0xFFC /* Component ID3 */
