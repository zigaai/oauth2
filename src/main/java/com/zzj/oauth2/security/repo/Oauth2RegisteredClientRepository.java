package com.zzj.oauth2.security.repo;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.zzj.oauth2.security.model.Oauth2RegisteredClient;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface Oauth2RegisteredClientRepository extends BaseMapper<Oauth2RegisteredClient> {

}
