import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V4 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "27a5fb98-fe8b-561c-b490-e04257e7dd1c"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L807-L822"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "49c912f29f5ffbd90366a510285ef3f06c804af86829808c175c8be519ce01c4"
		score = 85
		quality = 85
		tags = "FILE"

	strings:
		$DK_format1 = "/c format %c: /Y /Q" ascii
		$DK_format2 = "/c format %c: /Y /X /FS:NTFS" ascii
		$DK_physicaldrive = "PhysicalDrive%d" wide
		$DK_shutdown = "shutdown /r /t %d"

	condition:
		uint16(0)==0x5A4D and all of ($DK*)
}
