import "pe"

rule SIGNATURE_BASE_APT_FIN7_Strings_Aug18_1
{
	meta:
		description = "Detects strings from FIN7 report in August 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "9b940986-e41b-5fbf-9e42-cb0fd550e541"
		date = "2018-08-01"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_fin7.yar#L13-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "89d2f8f28a7ab0e78c53d8c41b45efa60cfa9ff72306c49197f52342d9a3c546"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b6354e46af0d69b6998dbed2fceae60a3b207584e08179748e65511d45849b00"

	strings:
		$s1 = "&&call %a01%%a02% /e:jscript" ascii
		$s2 = "wscript.exe //b /e:jscript %TEMP%" ascii
		$s3 = " w=wsc@ript /b " ascii
		$s4 = "@echo %w:@=%|cmd" ascii
		$s5 = " & wscript //b /e:jscript"

	condition:
		1 of them
}
