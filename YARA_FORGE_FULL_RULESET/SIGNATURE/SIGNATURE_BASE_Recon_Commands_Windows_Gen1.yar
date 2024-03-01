rule SIGNATURE_BASE_Recon_Commands_Windows_Gen1 : FILE
{
	meta:
		description = "Detects a set of reconnaissance commands on Windows systems"
		author = "Florian Roth (Nextron Systems)"
		id = "bc95265c-780d-5451-bd12-d14495877e46"
		date = "2017-07-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/MSJCxP"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_recon_indicators.yar#L12-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "36beb09c428949140cb007c1022c385c9a1ae4eea8c1f1a419f96b36b8030c7c"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "netstat -an" ascii
		$s2 = "net view" ascii fullword
		$s3 = "net user" ascii fullword
		$s4 = "whoami" ascii
		$s5 = "tasklist /v" ascii
		$s6 = "systeminfo" ascii
		$s7 = "net localgroup administrators" ascii
		$s8 = "net user administrator" ascii
		$s9 = "regedit -e " ascii
		$s10 = "tasklist /svc" ascii
		$s11 = "regsvr32 /s /u " ascii
		$s12 = "CreateObject(\"WScript.Shell\").RegWrite" ascii
		$s13 = "bitsadmin /rawreturn /transfer getfile" ascii
		$s14 = "wmic qfe list full" ascii
		$s15 = "schtasks.exe /create " ascii nocase
		$s16 = "wmic share get" ascii
		$s17 = "wmic nteventlog get" ascii
		$s18 = "wevtutil cl " ascii
		$s19 = "sc query type= service" ascii
		$s20 = "arp -a " ascii
		$fp1 = "avdapp.dll" fullword wide
		$fp2 = "keyword.command.batchfile" ascii
		$fp3 = ".sublime-settings" ascii

	condition:
		filesize <1000KB and 4 of them and not 1 of ($fp*)
}
