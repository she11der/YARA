rule ESET_Moose_2
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "74372984-dace-5665-a5d0-39b8d1002fa1"
		date = "2016-10-02"
		modified = "2016-11-01"
		reference = "http://www.welivesecurity.com/2016/11/02/linuxmoose-still-breathing/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/moose/linux-moose.yar#L78-L110"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "3f50d2d81d4c27e44d93804adcf93971017767ed0e020447cdb343931c2fbc43"
		score = 75
		quality = 80
		tags = ""
		Author = "Thomas Dupuy"
		Description = "Linux/Moose malware active since September 2015"
		Contact = "github@eset.com"
		License = "BSD 2-Clause"

	strings:
		$s1 = "Modules are loaded"
		$s2 = "--scrypt"
		$s3 = "http://"
		$s4 = "https://"
		$s5 = "processor "
		$s6 = "cpu model "
		$s7 = "Host: www.challpok.cn"
		$s8 = "Cookie: PHPSESSID=%s; nhash=%s; chash=%s"
		$s9 = "fail!"
		$s10 = "H3lL0WoRlD"
		$s11 = "crondd"
		$s12 = "cat /proc/cpuinfo"
		$s13 = "Set-Cookie: PHPSESSID="
		$s14 = "Set-Cookie: LP="
		$s15 = "Set-Cookie: WL="
		$s16 = "Set-Cookie: CP="
		$s17 = "Loading modules..."
		$s18 = "-nobg"

	condition:
		ESET_Is_Elf_PRIVATE and 5 of them
}
