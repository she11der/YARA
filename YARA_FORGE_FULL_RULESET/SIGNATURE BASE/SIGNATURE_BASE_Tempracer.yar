rule SIGNATURE_BASE_Tempracer : FILE
{
	meta:
		description = "Detects privilege escalation tool - file TempRacer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "edba6471-9720-5aad-8c15-386197700c83"
		date = "2016-03-30"
		modified = "2023-12-05"
		reference = "http://www.darknet.org.uk/2016/03/tempracer-windows-privilege-escalation-tool/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_tempracer.yar#L10-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e17d80c4822d16371d75e1440b6ac44af490b71fbee1010a3e8a5eca94d22bb3"
		logic_hash = "37355456e13ea9fa6429b68970e0450f4ddbd8da81c070a0383b1e048a05e35a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\obj\\Release\\TempRacer.pdb" ascii
		$s2 = "[+] Injecting into " fullword wide
		$s3 = "net localgroup administrators alex /add" fullword wide
		$s4 = "[+] File: {0} renamed to {1}" fullword wide
		$s5 = "[+] Blocking " fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <25KB and 1 of them ) or (4 of them )
}
