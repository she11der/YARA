import "pe"

rule SIGNATURE_BASE_Sig_238_Listip
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file listip.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "417faf20-ee07-5c3e-bfcf-89599e38e62e"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1536-L1554"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
		logic_hash = "db5cc21e8c76fdd10953ba0f06c4a1ad319ee522d9def7777dad66612b51edfc"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
		$s2 = "ERROR No.2!!! Program Terminate." fullword ascii
		$s4 = "Local Host Name: %s" fullword ascii
		$s5 = "Packed by exe32pack 1.38" fullword ascii
		$s7 = "Local Computer Name: %s" fullword ascii
		$s8 = "Local IP Adress: %s" fullword ascii

	condition:
		all of them
}
