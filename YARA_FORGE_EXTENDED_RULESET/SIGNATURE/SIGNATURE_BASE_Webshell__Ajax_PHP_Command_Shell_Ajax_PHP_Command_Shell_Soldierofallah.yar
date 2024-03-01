rule SIGNATURE_BASE_Webshell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_Soldierofallah
{
	meta:
		description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a158d158-d48d-514c-8b7b-4b6a4a10d021"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6755-L6775"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0b9e0d96c8a618a4883235e8c5c9a03a1e0b586cb4b30e0273e24c35ee5ee502"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
		hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
		hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"

	strings:
		$s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword
		$s2 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword
		$s3 = "$dt = $_POST['filecontent'];" fullword
		$s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword
		$s6 = "print \"Sorry, none of the command functions works.\";" fullword
		$s11 = "document.cmdform.command.value='';" fullword
		$s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"

	condition:
		3 of them
}
