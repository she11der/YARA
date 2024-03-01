import "pe"

rule SIGNATURE_BASE_Sig_238_Eee
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file eee.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "9d3ad3a9-0498-5ca3-ac19-f250cb10c4d3"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1572-L1591"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
		logic_hash = "b12c11f46125a33a2d7d9d02f25762c07b9d5088f70887c000b29e82a7921399"
		score = 60
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "szj1230@yesky.com" fullword wide
		$s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
		$s4 = "MailTo:szj1230@yesky.com" fullword wide
		$s5 = "Command1_Click" fullword ascii
		$s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
		$s11 = "vb5chs.dll" fullword ascii
		$s12 = "MSVBVM50.DLL" fullword ascii

	condition:
		all of them
}
