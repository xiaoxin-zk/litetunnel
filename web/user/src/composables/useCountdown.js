import { onBeforeUnmount, ref } from 'vue'

export function useCountdown(seconds = 60) {
  const countdown = ref(0)
  let timer = null

  function stop() {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  function start() {
    stop()
    countdown.value = seconds
    timer = setInterval(() => {
      countdown.value -= 1
      if (countdown.value <= 0) stop()
    }, 1000)
  }

  onBeforeUnmount(stop)

  return { countdown, start, stop }
}
