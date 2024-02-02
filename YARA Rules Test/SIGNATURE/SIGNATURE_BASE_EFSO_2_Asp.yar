rule SIGNATURE_BASE_EFSO_2_Asp
{
	meta:
		description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "f0566790-b41c-5167-b7ec-19e7d04256d1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4562-L4573"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b5fde9682fd63415ae211d53c6bfaa4d"
		logic_hash = "15e5419854bcbb08f28fff1e266cca7a004f01ec0a5c313c107ec17c3aa7ffee"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Ejder was HERE"
		$s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"

	condition:
		2 of them
}