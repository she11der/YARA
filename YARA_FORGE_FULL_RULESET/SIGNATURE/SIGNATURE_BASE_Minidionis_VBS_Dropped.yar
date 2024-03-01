rule SIGNATURE_BASE_Minidionis_VBS_Dropped : FILE
{
	meta:
		description = "Dropped File - 1.vbs"
		author = "Florian Roth (Nextron Systems)"
		id = "f0116861-4216-504a-a39b-463e7535a2b3"
		date = "2015-07-21"
		modified = "2023-12-05"
		reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_minidionis.yar#L72-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "97dd1ee3aca815eb655a5de9e9e8945e7ba57f458019be6e1b9acb5731fa6646"
		logic_hash = "a24fe4cdff6dd7951af10710eb63ab1fd90ab0e43bbce4388d6687abac206da5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Wscript.Sleep 5000" ascii
		$s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
		$s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
		$s4 = "If(FSO.FileExists(\"" ascii
		$s5 = "then FSO.DeleteFile(\".\\" ascii

	condition:
		filesize <1KB and all of them and $s1 in (0..40)
}
