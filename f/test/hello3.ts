import '@slack/web-api'
import * as wmill from 'windmill-client';

export async function main() {
  const { token } = await wmill.getResource('u/alex/test1234')
  console.log('ta', token)
  return "Hello world";
}