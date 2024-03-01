import "pe"

rule SIGNATURE_BASE_Paexec : FILE
{
	meta:
		description = "Detects remote access tool PAEXec (like PsExec) - file PAExec.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ee564534-b921-5639-a7ed-5da79d6bf86a"
		date = "2017-03-27"
		modified = "2023-12-05"
		reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4649-L4669"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "30478d90756a9ea362c40236518fe9013e5e5683641b7e7e1ad33aa3b5587e04"
		score = 40
		quality = 85
		tags = "FILE"
		hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"

	strings:
		$x1 = "Ex: -rlo C:\\Temp\\PAExec.log" fullword ascii
		$x2 = "Can't enumProcesses - Failed to get token for Local System." fullword wide
		$x3 = "PAExec %s - Execute Programs Remotely" fullword wide
		$x4 = "\\\\%s\\pipe\\PAExecIn%s%u" fullword wide
		$x5 = "\\\\.\\pipe\\PAExecIn%s%u" fullword wide
		$x6 = "%%SystemRoot%%\\%s.exe" fullword wide
		$x7 = "in replacement for PsExec, so the command-line usage is identical, with " fullword ascii
		$x8 = "\\\\%s\\ADMIN$\\PAExec_Move%u.dat" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of ($x*)) or (3 of them )
}
