rule SIGNATURE_BASE_APT30_Sample_2 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "821a2de9-48c4-58d8-acc4-1e25025ab5cf"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt30_backspace.yar#L28-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0359ffbef6a752ee1a54447b26e272f4a5a35167"
		logic_hash = "e34dbb90fc868b0619d3d2aa1b6176252836a6ae72e6f52b1eba632054f7c272"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ForZRLnkWordDlg.EXE" fullword wide
		$s1 = "ForZRLnkWordDlg Microsoft " fullword wide
		$s9 = "ForZRLnkWordDlg 1.0 " fullword wide
		$s11 = "ForZRLnkWordDlg" fullword wide
		$s12 = " (C) 2011" fullword wide

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
