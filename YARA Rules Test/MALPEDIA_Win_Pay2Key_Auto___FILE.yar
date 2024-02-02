rule MALPEDIA_Win_Pay2Key_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "26097eea-fdd3-5ff6-a78a-aae3970171ae"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pay2key"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pay2key_auto.yar#L1-L131"
		license_url = "N/A"
		logic_hash = "fed562ca29ad610b012032606168f69e452506f6e6212e1bb41332762ffb58be"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { f7d1 33d2 3b4dfc 8bcb 0f43d0 3bd7 0f43fa }
		$sequence_1 = { e8???????? 8d4e2c e8???????? 8d4e14 e8???????? c74604???????? 8b7e10 }
		$sequence_2 = { ffd7 837d1c08 8d5508 8d7508 0f435508 0f437508 }
		$sequence_3 = { c745fc00000000 833e00 7517 68de020000 68???????? 68???????? }
		$sequence_4 = { 50 e8???????? 83ec18 c645fc05 8bcc 896584 c7411000000000 }
		$sequence_5 = { 3bf7 0f8595f7ffff 83cfff c745fc07000000 8b750c 85f6 7429 }
		$sequence_6 = { eb05 6880000000 8bce e8???????? 8b4e20 8bc3 8b09 }
		$sequence_7 = { c7461000000000 7202 8b36 33c0 668906 8db758030000 8b4614 }
		$sequence_8 = { 3bf7 758c 8b5dec ff7314 8b35???????? ffd6 }
		$sequence_9 = { eb02 33c0 894758 8d5758 8a4304 88475c e8???????? }

	condition:
		7 of them and filesize <2252800
}