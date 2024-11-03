from redis.cluster import RedisCluster as Redis

redis = Redis(host="redis", port=6379, decode_responses=True)

