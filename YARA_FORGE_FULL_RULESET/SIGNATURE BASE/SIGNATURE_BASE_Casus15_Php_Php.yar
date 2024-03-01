rule SIGNATURE_BASE_Casus15_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ba6748a2-fb80-5eda-816c-155bab9285e5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3682-L3694"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
		logic_hash = "6ee7a07163d33ca329d3be2084406629711db14db4605e8413ee963eb0f9d5a7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
		$s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
		$s3 = "value='Calistirmak istediginiz "

	condition:
		1 of them
}
