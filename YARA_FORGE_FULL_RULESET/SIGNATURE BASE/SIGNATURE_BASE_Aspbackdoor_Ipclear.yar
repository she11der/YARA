import "pe"

rule SIGNATURE_BASE_Aspbackdoor_Ipclear
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ipclear.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "71ebecea-721f-5c5d-9997-6a57f070d91c"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2609-L2626"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9f8fdfde4b729516330eaeb9141fb2a7ff7d0098"
		logic_hash = "49fbe844a99aa8cae25db90e1d8cdeee13c81293bba7b3201afc4748cb0a6a7c"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Set ServiceObj = GetObject(\"WinNT://\" & objNet.ComputerName & \"/w3svc\")" fullword ascii
		$s1 = "wscript.Echo \"USAGE:KillLog.vbs LogFileName YourIP.\"" fullword ascii
		$s2 = "Set txtStreamOut = fso.OpenTextFile(destfile, ForWriting, True)" fullword ascii
		$s3 = "Set objNet = WScript.CreateObject( \"WScript.Network\" )" fullword ascii
		$s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii

	condition:
		all of them
}
