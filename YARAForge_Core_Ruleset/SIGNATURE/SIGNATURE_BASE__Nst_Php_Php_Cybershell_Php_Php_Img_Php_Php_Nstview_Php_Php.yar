rule SIGNATURE_BASE__Nst_Php_Php_Cybershell_Php_Php_Img_Php_Php_Nstview_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "cc4dc0e9-dbb1-560b-ae36-23d3e16a407f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5397-L5413"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "afc0b1c83644aa323d308471e5978b6b03f444f5f46fbaddac28ff42d524df1e"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "ef8828e0bc0641a655de3932199c0527"
		hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash3 = "4745d510fed4378e4b1730f56f25e569"

	strings:
		$s0 = "@$rto=$_POST['rto'];" fullword
		$s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
		$s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword

	condition:
		2 of them
}