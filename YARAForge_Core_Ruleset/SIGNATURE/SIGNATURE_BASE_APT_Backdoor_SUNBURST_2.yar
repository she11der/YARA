rule SIGNATURE_BASE_APT_Backdoor_SUNBURST_2
{
	meta:
		description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
		author = "FireEye"
		id = "329071d5-c9c6-5ae1-a514-aea9f4037bac"
		date = "2020-12-14"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_solarwinds_sunburst.yar#L28-L79"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2bf0697b110bca88f712cbccaf0d2ba614d6093d6d9595659aefe088848d3826"
		score = 85
		quality = 83
		tags = ""

	strings:
		$a = "0y3Kzy8BAA==" wide
		$aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
		$ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
		$ac = "C88sSs1JLS4GAA==" wide
		$ad = "C/UEAA==" wide
		$ae = "C89MSU8tKQYA" wide
		$af = "8wvwBQA=" wide
		$ag = "cyzIz8nJBwA=" wide
		$ah = "c87JL03xzc/LLMkvysxLBwA=" wide
		$ai = "88tPSS0GAA==" wide
		$aj = "C8vPKc1NLQYA" wide
		$ak = "88wrSS1KS0xOLQYA" wide
		$al = "c87PLcjPS80rKQYA" wide
		$am = "Ky7PLNAvLUjRBwA=" wide
		$an = "06vIzQEA" wide
		$b = "0y3NyyxLLSpOzIlPTgQA" wide
		$c = "001OBAA=" wide
		$d = "0y0oysxNLKqMT04EAA==" wide
		$e = "0y3JzE0tLknMLQAA" wide
		$f = "003PyU9KzAEA" wide
		$h = "0y1OTS4tSk1OBAA=" wide
		$i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
		$j = "c8rPSQEA" wide
		$k = "c8rPSfEsSczJTAYA" wide
		$l = "c60oKUp0ys9JAQA=" wide
		$m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
		$n = "8yxJzMlMBgA=" wide
		$o = "88lMzygBAA==" wide
		$p = "88lMzyjxLEnMyUwGAA==" wide
		$q = "C0pNL81JLAIA" wide
		$r = "C07NzXTKz0kBAA==" wide
		$s = "C07NzXTKz0nxLEnMyUwGAA==" wide
		$t = "yy9IzStOzCsGAA==" wide
		$u = "y8svyQcA" wide
		$v = "SytKTU3LzysBAA==" wide
		$w = "C84vLUpOdc5PSQ0oygcA" wide
		$x = "C84vLUpODU4tykwLKMoHAA==" wide
		$y = "C84vLUpO9UjMC07MKwYA" wide
		$z = "C84vLUpO9UjMC04tykwDAA==" wide

	condition:
		($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}