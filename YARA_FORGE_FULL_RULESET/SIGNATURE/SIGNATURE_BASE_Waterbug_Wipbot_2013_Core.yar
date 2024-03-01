rule SIGNATURE_BASE_Waterbug_Wipbot_2013_Core : FILE
{
	meta:
		description = "Symantec Waterbug Attack - Trojan.Wipbot core + core; garbage appended data (PDF Exploit leftovers) + wipbot dropper; fake AdobeRd32 Error"
		author = "Symantec Security Response"
		id = "2e8ccce9-d8ba-573d-b532-76d8e2ed5442"
		date = "2015-01-22"
		modified = "2023-01-27"
		reference = "http://t.co/rF35OaAXrl"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_waterbug.yar#L34-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "59e1363225b1f7765e953e3d6803270b82f4268431d92ef00ed1010df0793e5f"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$code1 = { 89 47 0C C7 47 10 90 C2 04 00 C7 47 14 90 C2 10 00 C7 47 18 90 90 60 68 89 4F 1C C7 47 20 90 90 90 B8 89 4F 24 C7 47 28 90 FF D0 61 C7 47 2C 90 C2 04 00}
		$code2 = { 85 C0 75 25 8B 0B BF ?? ?? ?? ?? EB 17 69 D7 0D 66 19 00 8D BA 5F F3 6E 3C 89 FE C1 EE 10 89 F2 30 14 01 40 3B 43 04 72 E4}
		$code3 = {90 90 90 ?? B9 00 4D 5A 90 00 03 00 00 00 82 04}
		$code4 = {55 89 E5 5D C3 55 89 E5 83 EC 18 8B 45 08 85 C0}

	condition:
		uint16(0)==0x5A4D and (($code1 or $code2) or ($code3 and $code4))
}
