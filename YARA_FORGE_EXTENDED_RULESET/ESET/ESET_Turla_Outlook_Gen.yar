import "pe"

rule ESET_Turla_Outlook_Gen
{
	meta:
		description = "Turla Outlook malware"
		author = "ESET Research"
		id = "efef2443-c941-54c2-abfa-bbe29c53d930"
		date = "2018-05-09"
		modified = "2018-09-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/turla/turla-outlook.yar#L42-L74"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "f709e517e9d957775601670c426cc9def1c4104cb1ff647d269800d2af4372c7"
		score = 75
		quality = 78
		tags = ""
		version = 2
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = "Outlook Express" ascii wide
		$s2 = "Outlook watchdog" ascii wide
		$s3 = "Software\\RIT\\The Bat!" ascii wide
		$s4 = "Mail Event Window" ascii wide
		$s5 = "Software\\Mozilla\\Mozilla Thunderbird\\Profiles" ascii wide
		$s6 = "%%PDF-1.4\n%%%c%c\n" ascii wide
		$s7 = "%Y-%m-%dT%H:%M:%S+0000" ascii wide
		$s8 = "rctrl_renwnd32" ascii wide
		$s9 = "NetUIHWND" ascii wide
		$s10 = "homePostalAddress" ascii wide
		$s11 = "/EXPORT;OVERRIDE;START=-%d;END=-%d;FOLDER=%s;OUT=" ascii wide
		$s12 = "Re:|FWD:|AW:|FYI:|NT|QUE:" ascii wide
		$s13 = "IPM.Note" ascii wide
		$s14 = "MAPILogonEx" ascii wide
		$s15 = "pipe\\The Bat! %d CmdLine" ascii wide
		$s16 = "PowerShellRunner.dll" ascii wide
		$s17 = "cmd container" ascii wide
		$s18 = "mapid.tlb" ascii wide nocase
		$s19 = "Content-Type: F)*+" ascii wide fullword

	condition:
		ESET_Not_Ms_PRIVATE and 5 of them
}
