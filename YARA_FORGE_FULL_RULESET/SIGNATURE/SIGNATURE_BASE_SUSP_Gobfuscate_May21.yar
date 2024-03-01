rule SIGNATURE_BASE_SUSP_Gobfuscate_May21 : FILE
{
	meta:
		description = "Identifies binaries obfuscated with gobfuscate"
		author = "James Quinn"
		id = "ae518296-b1c3-568c-bae0-3e0a6f7600ba"
		date = "2021-05-14"
		modified = "2023-12-05"
		reference = "https://github.com/unixpickle/gobfuscate"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_gobfuscate.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e2f9720356e50ac34d08f351bf48987bcf697314d115161048521df79746142f"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = { 0f b6 ?? ?? ?? 0f b6 ?? ?? ?? 31 D1 88 ?? ?? ?? 48 FF C0 48 83 f8 ?? 7c E7 48 C7 }
		$s2 = { 0F b6 ?? ?? ?? 31 DA 88 ?? ?? ?? 40 83 ?? ?? 7D 09 0F B6 }

	condition:
		filesize <50MB and any of them
}
