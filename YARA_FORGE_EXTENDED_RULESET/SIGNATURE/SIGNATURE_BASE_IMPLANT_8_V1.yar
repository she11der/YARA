import "pe"

rule SIGNATURE_BASE_IMPLANT_8_V1 : FILE
{
	meta:
		description = "HAMMERTOSS / HammerDuke Implant by APT29"
		author = "US CERT"
		id = "eeaa43c1-6004-5d64-bdc1-f84b3c68d741"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1383-L1411"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "437bda331405f9203747ffbfb107ec26e33973ebfc9f02e153697f7b8c22ad4f"
		score = 65
		quality = 85
		tags = "FILE"

	strings:
		$DOTNET = "mscorlib" ascii
		$REF_URL = "https://www.google.com/url?sa=" wide
		$REF_var_1 = "&rct=" wide
		$REF_var_2 = "&q=&esrc=" wide
		$REF_var_3 = "&source=" wide
		$REF_var_4 = "&cd=" wide
		$REF_var_5 = "&ved=" wide
		$REF_var_6 = "&url=" wide
		$REF_var_7 = "&ei=" wide
		$REF_var_8 = "&usg=" wide
		$REF_var_9 = "&bvm=" wide

	condition:
		( uint16(0)==0x5A4D) and ($DOTNET) and ($REF_URL) and (3 of ($REF_var*))
}
