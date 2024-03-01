import "pe"
import "math"

rule SIGNATURE_BASE_Stonedrill_VBS_1 : FILE
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		author = "Florian Roth (Nextron Systems)"
		id = "a7ee3bd4-eeae-5eb4-92e7-9601ec17300a"
		date = "2017-03-07"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_stonedrill.yar#L172-L192"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "79416d27a6a09d544becd84f8e551c09b94c97181f8fddc481f47e42763d47ac"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"

	strings:
		$x1 = "wmic /NameSpace:\\\\root\\default Class StdRegProv Call SetStringValue hDefKey = \"&H80000001\" sSubKeyName = \"Software\\Micros" ascii
		$x2 = "ping 1.0.0.0 -n 1 -w 20000 > nul" fullword ascii
		$s1 = "WshShell.CopyFile \"%COMMON_APPDATA%\\Chrome\\" ascii
		$s2 = "WshShell.DeleteFile \"%temp%\\" ascii
		$s3 = "WScript.Sleep(10 * 1000)" fullword ascii
		$s4 = "Set WshShell = CreateObject(\"Scripting.FileSystemObject\") While WshShell.FileExists(\"" ascii
		$s5 = " , \"%COMMON_APPDATA%\\Chrome\\" ascii

	condition:
		( filesize <1KB and 1 of ($x*) or 2 of ($s*))
}
