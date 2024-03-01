rule MALPEDIA_Win_Ramnit_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "9f7bb136-c877-5703-86ba-5c3c0993dd1e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ramnit"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ramnit_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "a743fa525eb529644f7aae0eeccbdf2bcc4af05febdbf59986022c9547272ab4"
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
		$sequence_0 = { 3a06 7512 47 46 e2f6 b801000000 59 }
		$sequence_1 = { 750b 4f 3b7d08 73e7 bf00000000 }
		$sequence_2 = { 57 56 fc 807d1401 }
		$sequence_3 = { 5f 59 5a 5b c9 c20800 55 }
		$sequence_4 = { ff750c ff75fc e8???????? 0bc0 7429 }
		$sequence_5 = { 8bc7 5a 5b 59 5f }
		$sequence_6 = { 8bc1 f7d0 48 59 5f 5e }
		$sequence_7 = { f3a4 fc 5e 5f 59 5a }
		$sequence_8 = { 8bd7 2b5508 59 5f 5e }
		$sequence_9 = { 8b5d0c 4b f7d3 23c3 }

	condition:
		7 of them and filesize <470016
}
