rule SIGNATURE_BASE_Empire_Invoke_Dllinjection : FILE
{
	meta:
		description = "Detects Empire component - file Invoke-DllInjection.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "6aa14e8f-9801-5cd3-beb0-955e19d25503"
		date = "2016-11-05"
		modified = "2023-12-05"
		reference = "https://github.com/adaptivethreat/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_empire.yar#L322-L335"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "450ca96dd7c80275d7e4eaf07a7229e27530c373b8d79af5be8f4a741daef448"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"

	strings:
		$s1 = "-Dll evil.dll" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <40KB and 1 of them ) or all of them
}
