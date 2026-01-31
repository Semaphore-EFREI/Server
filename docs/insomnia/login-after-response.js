const json = await insomnia.response.json();
if (json?.accessToken) {
  await insomnia.environment.set("accessToken", json.accessToken);
}
if (json?.refreshToken) {
  await insomnia.environment.set("refreshToken", json.refreshToken);
}
if (json?.user?.id) {
  await insomnia.environment.set("userId", json.user.id);
}
