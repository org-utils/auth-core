import { randomUUID } from "node:crypto";

export const nowSeconds = (): number => {
  return Math.floor(Date.now() / 1000);
};
export const uniqueId = (): string => {
  return randomUUID();
};
