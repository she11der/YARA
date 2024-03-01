rule SIGNATURE_BASE_Wscript_Shell_Powershell_Combo : FILE
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		author = "Florian Roth (Nextron Systems)"
		id = "265ec471-d9ed-5cb6-a32b-cfa62fccdf64"
		date = "2018-02-07"
		modified = "2023-12-05"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_susp.yar#L162-L183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0ab5808593c999c1ce342051a8e292153aa20516cf48071565d677399adfb160"
		score = 50
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"

	strings:
		$s1 = ".CreateObject(\"WScript.Shell\")" ascii
		$p1 = "powershell.exe" fullword ascii
		$p2 = "-ExecutionPolicy Bypass" fullword ascii
		$p3 = "[System.Convert]::FromBase64String(" ascii
		$fp1 = "Copyright: Microsoft Corp." ascii

	condition:
		filesize <400KB and $s1 and 1 of ($p*) and not 1 of ($fp*)
}
