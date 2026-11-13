// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function readSetting(config: Record<string, any>, key: string): any {
  return config[key]
}
