import "pe"

rule SIGNATURE_BASE_IMPLANT_3_V3 : FILE
{
	meta:
		description = "X-Agent/CHOPSTICK Implant by APT28"
		author = "US CERT"
		id = "ce82511e-715a-53cb-98e5-5d51b94726d5"
		date = "2017-02-10"
		modified = "2021-03-15"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L466-L485"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "313f837b90bcf09455427e4411acb5406f4dae9d69373d8d2c0cfc014e27ee96"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$STR1 = ".?AVAgentKernel@@"
		$STR2 = ".?AVIAgentModule@@"
		$STR3 = "AgentKernel"
		$fp1 = "Panda Security S.L." wide

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and 1 of ($STR*) and not 1 of ($fp*)
}
