rule SIGNATURE_BASE_APT_SH_Sandworm_Shell_Script_May20_1 : FILE
{
	meta:
		description = "Detects shell script used by Sandworm in attack against Exim mail server"
		author = "Florian Roth (Nextron Systems)"
		id = "21cf2c89-5511-5eb6-a2dd-4ad54ebfa2d1"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sandworm_exim_expl.yar#L103-L129"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b9116585e74ad6159cd31c0c8a84566f981a62ca5b5f82ace8b855a180461071"
		score = 75
		quality = 60
		tags = "FILE"
		hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
		hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"

	strings:
		$x1 = "echo \"GRANT ALL PRIVILEGES ON * . * TO 'mysqldb'@'localhost';\" >> init-file.txt" ascii fullword
		$x2 = "import base64,sys;exec(base64.b64decode({2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version" ascii fullword
		$x3 = "sed -i -e '/PasswordAuthentication/s/no/yes/g; /PermitRootLogin/s/no/yes/g;" ascii fullword
		$x4 = "useradd -M -l -g root -G root -b /root -u 0 -o mysql_db" ascii fullword
		$s1 = "/ip.php?port=${PORT}\"" ascii fullword
		$s2 = "sed -i -e '/PasswordAuthentication" ascii fullword
		$s3 = "PATH_KEY=/root/.ssh/authorized_keys" ascii fullword
		$s4 = "CREATE USER" ascii fullword
		$s5 = "crontab -l | { cat; echo" ascii fullword
		$s6 = "mysqld --user=mysql --init-file=/etc/opt/init-file.txt --console" ascii fullword
		$s7 = "sshkey.php" ascii fullword

	condition:
		uint16(0)==0x2123 and filesize <20KB and 1 of ($x*) or 4 of them
}
