import { Redis, Cluster, type RedisOptions, type ClusterOptions, type ClusterNode } from "ioredis";

export type RedisLikeClient = Redis | Cluster;

export type RedisClientConfig =
  | { mode: "standalone"; options: RedisOptions }
  | { mode: "sentinel"; options: RedisOptions & { sentinels: { host: string; port: number }[]; name: string } }
  | { mode: "cluster"; nodes: ClusterNode[]; options?: ClusterOptions }
  /** Bring your own already-connected ioredis instance (recommended for connection reuse). */
  | { mode: "instance"; client: RedisLikeClient };

/**
 * Creates (or passes through) an ioredis client. The auth-core package
 * itself never imports `ioredis` directly — only this adapter package does
 * — so the core stays Redis-free per the architecture requirements.
 */
export function createRedisClient(config: RedisClientConfig): RedisLikeClient {
  switch (config.mode) {
    case "instance":
      return config.client;
    case "standalone":
      return new Redis(config.options);
    case "sentinel":
      return new Redis(config.options);
    case "cluster":
      return new Cluster(config.nodes, config.options);
    default: {
      const exhaustive: never = config;
      throw new Error(`Unsupported redis client mode: ${JSON.stringify(exhaustive)}`);
    }
  }
}
