import "pe"

rule SIGNATURE_BASE_IMPLANT_4_V10 : FILE
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		id = "75c266ca-a27f-5ffe-a438-c35bbacfa70c"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L935-L966"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f22fd45eb77ff1a8202f4bd0d0c43787c8184300e96aff021e13371ae7bd5553"
		score = 85
		quality = 81
		tags = "FILE"

	strings:
		$ = {A1B05C72}
		$ = {EB3D0384}
		$ = {6F45594E}
		$ = {71815A4E}
		$ = {D5B03E72}
		$ = {6B43594E}
		$ = {F572993D}
		$ = {665D9DC0}
		$ = {0BE7A75A}
		$ = {F37443C5}
		$ = {A2A474BB}
		$ = {97DEEC67}
		$ = {7E0CB078}
		$ = {9C9678BF}
		$ = {4A37A149}
		$ = {8667416B}
		$ = {0A375BA4}
		$ = {DC505A8D}
		$ = {02F1F808}
		$ = {2C819712}

	condition:
		uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550 and 15 of them
}
