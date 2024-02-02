rule SIGNATURE_BASE_Webshell_Gamma_Web_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "43b4fc9f-8897-5553-8846-29d307efa885"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6418-L6432"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
		logic_hash = "1de868c4948a95272d288aeba3ac38b84bf6b33ede6b3b600b32530c85586404"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
		$s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
		$s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
		$s20 = "my $command = $self->query('command');" fullword

	condition:
		2 of them
}