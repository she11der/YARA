rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Shamoon : FILE
{
	meta:
		description = "Kwampirs Shamoon overlap"
		author = "FBI / cywatch@fbi.gov"
		id = "87d28867-383e-5e09-8369-63c8a4e3f966"
		date = "2020-01-14"
		modified = "2020-03-31"
		reference = "https://assets.documentcloud.org/documents/6821582/FLASH-CP-000118-MW-Downgraded-Version.pdf"
		source_url = "https://github.com/craiu/yararules/blob/2b3716b6991652d91c8b89c39944611ade164aaa/files/apt_zz_orangeworm.yara#L200-L221"
		license_url = "https://github.com/craiu/yararules/blob/2b3716b6991652d91c8b89c39944611ade164aaa/LICENSE"
		logic_hash = "43f352c3db016d2831d11a13ae6c0baf440fa464560090e00432780df6a8982d"
		score = 75
		quality = 60
		tags = "FILE"

	strings:
		$s1 = "g\\system32\\" fullword wide
		$s2 = "ztvttw" fullword wide
		$s3 = "lwizvm" fullword ascii
		$op1 = { 94 35 77 73 03 40 eb e9 }
		$op2 = { 80 7c 41 01 00 74 0a 3d }
		$op3 = { 74 0a 3d 00 94 35 77 }

	condition:
		(( uint16(0)==0x5a4d) and ( filesize <4000KB) and (3 of them ))
}
