import "pe"

rule SIGNATURE_BASE_Editserver
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "de6bf995-1c7c-561f-98df-e8748d5fb157"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1635-L1657"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
		logic_hash = "6a8f6fcf8f4a0ea5ac114150d7becbd716be0bb40cd45fd5c76a4a8a328e5e40"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii
		$x1 = "WinEggDrop Shell Congirator" fullword ascii

	condition:
		5 of ($s*) or $x1
}
