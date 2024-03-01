import "pe"

rule TRELLIX_ARC_Badbunny : RANSOMWARE FILE
{
	meta:
		description = "Bad Rabbit Ransomware"
		author = "Christiaan Beek"
		id = "190ee396-4c26-54f7-baac-bb45e3587488"
		date = "2017-10-24"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_BadRabbit.yar#L3-L47"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		logic_hash = "2879b8dc1ca0e86253354ac24b56d950878b23215b503da9b1d5faabd2c4bf9d"
		score = 75
		quality = 45
		tags = "RANSOMWARE, FILE"
		rule_version = "v1"
		malware_type = "ransomware"
		malware_family = "Ransom:W32/BadRabbit"
		actor_type = "Cybercrime"
		actor_group = "Unknown"
		hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"

	strings:
		$x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
		$x2 = "need to do is submit the payment and get the decryption password." fullword ascii
		$s3 = "If you have already got the password, please enter it below." fullword ascii
		$s4 = "dispci.exe" fullword wide
		$s5 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
		$s6 = "Run DECRYPT app at your desktop after system boot" fullword ascii
		$s7 = "Enter password#1: " fullword wide
		$s8 = "Enter password#2: " fullword wide
		$s9 = "C:\\Windows\\cscc.dat" fullword wide
		$s10 = "schtasks /Delete /F /TN %ws" fullword wide
		$s11 = "Password#1: " fullword ascii
		$s12 = "\\AppData" fullword wide
		$s13 = "Disk decryption completed" fullword wide
		$s14 = "Files decryption completed" fullword wide
		$s15 = "http://diskcryptor.net/" fullword wide
		$s16 = "Your personal installation key#1:" fullword ascii
		$s17 = ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg." wide
		$s18 = "Disable your anti-virus and anti-malware programs" fullword wide
		$s19 = "bootable partition not mounted" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and pe.imphash()=="94f57453c539227031b918edd52fc7f1" and (1 of ($x*) or 4 of them )) or ( all of them )
}
