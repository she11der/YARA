rule SIGNATURE_BASE_Webshell_Asp_Up
{
	meta:
		description = "Web Shell - file up.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1084-L1098"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f775e721cfe85019fe41c34f47c0d67c"
		logic_hash = "dff2896d2226ade08e74147121a0e0036e8545dfff36b48b5a0771c9c7d537e9"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
		$s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword

	condition:
		1 of them
}
