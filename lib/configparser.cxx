

static void parse_mock_conf(minerva_mock_conf_t &minerva_mock_conf,
		const char *mock_conf,
	       	unsigned int this_node)
{
	DBG("Loading libminerva_mock_conf from %s %u", mock_conf, this_node);
	std::ifstream in(mock_conf);
	std::string line;
	std::shared_ptr<minerva_mock_node_spec_t> node_spec;
	std::shared_ptr<minerva_mock_share_conf_t> share_spec;
	std::shared_ptr<minerva_mock_user_mapping_t> user_mapping;
	unsigned int lineno = 0;
	while (std::getline(in, line)) {
		++lineno;
		size_t pos = skip(line, 0, line.length());;
		if (pos == line.length() || line.compare(pos, 1, "#") == 0) {
			continue;
		}
		if (line[pos] == '[') {
			auto end = line.find(']', pos + 1);
			if (end == std::string::npos) {
				PARSE_FATAL("Parsing mock conf error at %s:%u",
						mock_conf, lineno);
			}
			std::string section = line.substr(pos + 1, end - pos - 1);
			if (share_spec) {
				assert(!node_spec);
				DBG("add share section %s Proto(%d:%d)",
					share_spec->name.c_str(),
					share_spec->primary_proto,
					share_spec->secondary_proto);
				minerva_mock_conf.shares.push_back(share_spec);
				share_spec = nullptr;
			}
			if (node_spec) {
				assert(!share_spec);
				int ret = add_node(minerva_mock_conf, node_spec);
				if (ret < 0) {
					PARSE_FATAL("add node section %u, error %d", node_spec->id, ret);
				}
				DBG("add node section %u", node_spec->id);
				node_spec = nullptr;
			}
			if (user_mapping) {
				DBG("Default User Mapping : NFS (%d, %d),"
				    " SMB (%s, %s)",
				    user_mapping->def.nfs_uid,
				    user_mapping->def.nfs_uid,
				    user_mapping->def.smb_user.c_str(),
				    user_mapping->def.smb_group.c_str());
				minerva_mock_conf.user_mapping = user_mapping;
				user_mapping = nullptr;
			}
			if (section.compare(0, 5, "node:") == 0) {
				uint32_t node_id = std::stoul(section.substr(5));
				if (node_id == 0 || node_id > 32) {
					PARSE_FATAL("Invalid node id %u at %s:%u",
							node_id, mock_conf, lineno);
				}
				if (minerva_mock_conf.nodes.size() > node_id) {
				       	if (minerva_mock_conf.nodes[node_id]) {
						PARSE_FATAL("Existed node id %lu at %s:%u",
								node_id, mock_conf, lineno);
					}
				} else {
					minerva_mock_conf.nodes.resize(node_id + 1);
				}
				node_spec = std::make_shared<minerva_mock_node_spec_t>(node_id);
			} else if (section.compare(0, 6, "share:") == 0) {
				share_spec = std::make_shared<minerva_mock_share_conf_t>(section.substr(6));
			} else if (section.compare(0, 13, "USER_MAPPING:") == 0) {
				user_mapping = std::make_shared<minerva_mock_user_mapping_t>();
			} else if (section != "FILESERVER") {
				PARSE_FATAL("Unexpected section %s at %s:%u",
						section.c_str(), mock_conf, lineno);
			}
		} else {
			auto sep = line.find('=', pos);
			if (sep == std::string::npos) {
				PARSE_FATAL("No '=' at %s:%u",
						mock_conf, lineno);
			}
			auto name = line.substr(pos, rskip(line, sep, pos) - pos);

			pos = skip(line, sep + 1, line.length());
			auto value = line.substr(pos, rskip(line, line.length(), pos) - pos);

			if (share_spec) {
				if (name == "type") {
					if (value == "HOME_SHARE") {
						share_spec->is_shard = true;
					} else if (value == "DEFAULT_SHARE") {
						share_spec->is_shard = false;
					} else {
						assert(false);
					}
				} else if (name == "uuid") {
					share_spec->uuid = value;
				} else if (name == "abe") {
					if (value == "yes") {
						share_spec->abe = true;
					} else if (value == "no") {
						share_spec->abe = false;
					} else {
						PARSE_FATAL("Unexpected boolean %s at %s:%u",
								value.c_str(), mock_conf, lineno);
					}
				} else if (name == "primary-protocol") {
					// Default to SMB if not specified.
					share_spec->primary_proto = (value == "NFS") ? NFS : SMB;
				} else if (name == "secondary-protocol") {
					if (value == "NFS") {
						share_spec->secondary_proto = NFS;
					} else if (value == "SMB") {
						share_spec->secondary_proto = SMB;
					} else {
						share_spec->secondary_proto = PROTOCOL_NONE;
					}
				} else if (name.compare(0, 3, "vg-") == 0) {
					share_spec->vgs.push_back(parse_vg(value));
				} else {
					share_spec->params[name] = value;
				}
			} else if (node_spec) {
				if (name == "uuid") {
					node_spec->uuid = value;
				} else if (name == "ext_ip") {
					node_spec->ext_ip = value;
				}
			} else if (user_mapping) {
				size_t sz;
				if (name == "nfs_uid") {
					user_mapping->def.nfs_uid =
						std::stoi(value, &sz);
					assert(sz == value.size());
				} else if (name == "nfs_gid") {
					user_mapping->def.nfs_gid =
						std::stoi(value, &sz);
					assert(sz == value.size());
				} else if (name == "smb_user") {
					user_mapping->def.smb_user = value;
				} else if (name == "smb_group") {
					user_mapping->def.smb_group = value;
				}
			} else {
				if (name == "hostname") {
					minerva_mock_conf.hostname = value;
				} else {
					minerva_mock_conf.params[name] = value;
				}
			}
		}
	}
	if (share_spec) {
		assert(!node_spec);
		DBG("add share section %s Proto(%d:%d)",
			share_spec->name.c_str(),
			share_spec->primary_proto,
			share_spec->secondary_proto);
		minerva_mock_conf.shares.push_back(share_spec);
	}
	if (node_spec) {
		assert(!share_spec);
		int ret = add_node(minerva_mock_conf, node_spec);
		if (ret < 0) {
			PARSE_FATAL("add node section %u, error %d", node_spec->id, ret);
		}
		DBG("add node section %u", node_spec->id);
		node_spec = nullptr;
	}

	if (this_node >= minerva_mock_conf.nodes.size()) {
		PARSE_FATAL("Invalid this_node %u", this_node);
	}

	auto &my_node = minerva_mock_conf.nodes[this_node];
	if (!my_node) {
		PARSE_FATAL("Invalid this_node %u", this_node);
	}
	minerva_mock_conf.node_uuid = my_node->uuid;
}

