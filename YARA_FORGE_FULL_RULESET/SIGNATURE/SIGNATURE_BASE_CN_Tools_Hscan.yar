rule SIGNATURE_BASE_CN_Tools_Hscan : FILE
{
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "82d9cd61-8cef-56b4-8dfe-a28edaa781b8"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1772-L1792"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		logic_hash = "9bc4800249bffcc4b8fc1191d600f0b9b2a7b0c1f067039c83c03671a0b4b5c5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
		$s3 = "%s -h www.target.com -all" fullword ascii
		$s4 = ".\\report\\%s-%s.html" fullword ascii
		$s5 = ".\\log\\Hscan.log" fullword ascii
		$s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
		$s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
		$s8 = ".\\conf\\mysql_pass.dic" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
