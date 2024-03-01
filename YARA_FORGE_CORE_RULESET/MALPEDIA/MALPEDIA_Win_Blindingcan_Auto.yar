rule MALPEDIA_Win_Blindingcan_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "cb880a40-09fd-57de-a5ce-976bc164d187"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blindingcan"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.blindingcan_auto.yar#L1-L180"
		license_url = "N/A"
		logic_hash = "7d6669fb427721c8bcc6cd766a15275abac3a422e034ffec946a676b43de9099"
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
		$sequence_0 = { 83c40c 68???????? 68???????? ff15???????? 689c040000 85c0 }
		$sequence_1 = { 750a 8b10 8994bdfcfdffff 47 83c00c 49 }
		$sequence_2 = { c785bcfdffff661fcba8 c785c0fdffffc0f0d181 c785c4fdffff1f08c3d4 c785c8fdffff28edbc6a c785ccfdffff12aff210 }
		$sequence_3 = { c745e4ef0dfff5 c745e85acd9c1d c745ec36c2f964 c745f0a70d9fae c745f48f2aedf1 }
		$sequence_4 = { c78594feffff657f9183 c78598feffffa78b5b05 c7859cfeffff87f53e0c c785a0feffff074f9b22 }
		$sequence_5 = { c745ac84b1df57 c745b0c8cbfee9 c745b4567e337f c745b8e958e686 }
		$sequence_6 = { c78548feffffdfc2f62c c7854cfeffff17516633 c78550fefffff76c7e7e c78554feffffa14b0c27 c78558feffff10c0aac6 c7855cfeffff489a8471 c78560feffff9cab4ad6 }
		$sequence_7 = { 740c a810 7408 c68435a8fcffff01 46 83fe1a }
		$sequence_8 = { f7fe 8bca e8???????? 85c0 7409 e8???????? }
		$sequence_9 = { 55 4154 4155 488da8e8f3ffff 4881ec000d0000 488b05???????? 4833c4 }
		$sequence_10 = { 8bd5 664489642422 6689442420 895c2428 e8???????? 8bd3 488bcf }
		$sequence_11 = { 85c0 751b e8???????? 4885c0 7461 448bc7 488d55c0 }
		$sequence_12 = { 81e909200000 746e 83e907 745f ffc9 744d ffc9 }
		$sequence_13 = { 410fb6c4 0fb68c2810be0100 41335518 400fb6c6 0fb6842810be0100 c1e108 33c8 }
		$sequence_14 = { 488b4dc8 488d45c0 4c8d4db0 4889442428 488d0552d30100 488d1586340100 4533c0 }
		$sequence_15 = { ff15???????? 4883ceff 4c8be8 4889442440 483bc6 752d ff15???????? }

	condition:
		7 of them and filesize <363520
}
