private rule ESET_Prikormkamodule_PRIVATE
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "f99ed5f7-9ccc-5543-9224-6f865578f81e"
		date = "2019-08-28"
		modified = "2019-08-28"
		reference = "https://github.com/eset/malware-ioc"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/groundbait/prikormka.yar#L53-L110"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "d5d7f1a46cbf9ff545c0fa840228d19ee7d45307078b4ae0b5a2fdf1c94d2978"
		score = 75
		quality = 26
		tags = ""

	strings:
		$mz = { 4D 5A }
		$str00 = {6D 70 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
		$str01 = {68 6C 70 75 63 74 66 2E 64 6C 6C 00 43 79 63 6C 65}
		$str02 = {00 6B 6C 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
		$str03 = {69 6F 6D 75 73 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67}
		$str04 = {61 74 69 6D 6C 2E 64 6C 6C 00 4B 69 63 6B 49 6E 50 6F 69 6E 74}
		$str05 = {73 6E 6D 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
		$str06 = {73 63 72 73 68 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
		$str07 = {50 52 55 5C 17 51 58 17 5E 4A}
		$str08 = {60 4A 55 55 4E 53 58 4B 17 52 57 17 5E 4A}
		$str09 = {55 52 5D 4E 5B 4A 5D 17 51 58 17 5E 4A}
		$str10 = {60 4A 55 55 4E 61 17 51 58 17 5E 4A}
		$str11 = {39 5D 17 1D 1C 0A 3C 57 59 3B 1C 1E 57 58 4C 54 0F}
		$str12 = "ZxWinDeffContex" ascii wide
		$str13 = "Paramore756Contex43" wide
		$str14 = "Zw_&one@ldrContext43" wide
		$str15 = "A95BL765MNG2GPRS"
		$str16 = "helpldr.dll" wide fullword
		$str17 = "swma.dll" wide fullword
		$str18 = "iomus.dll" wide fullword
		$str19 = "atiml.dll" wide fullword
		$str20 = "hlpuctf.dll" wide fullword
		$str21 = "hauthuid.dll" ascii wide fullword
		$str22 = "[roboconid][%s]" ascii fullword
		$str23 = "[objectset][%s]" ascii fullword
		$str24 = "rbcon.ini" wide fullword
		$str25 = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
		$str26 = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword
		$str27 = ":\\!PROJECTS!\\Mina\\2015\\" ascii
		$str28 = "\\PZZ\\RMO\\" ascii
		$str29 = ":\\work\\PZZ" ascii
		$str30 = "C:\\Users\\mlk\\" ascii
		$str31 = ":\\W o r k S p a c e\\" ascii
		$str32 = "D:\\My\\Projects_All\\2015\\" ascii
		$str33 = "\\TOOLS PZZ\\Bezzahod\\" ascii

	condition:
		($mz at 0) and ( any of ($str*))
}
