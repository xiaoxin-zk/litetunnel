import { onBeforeUnmount, ref } from 'vue'

// useCountdown 管理「发送验证码后的冷却秒数」。
//
// 统一封装的原因：三个页面各自写了一份 setInterval，且都没有在卸载时清理——
// 用户切走页面后计时器仍在跑，继续修改一个已经卸载的组件的响应式状态；
// 反复进出页面还会叠加多个计时器，倒计时跳得越来越快。
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
    // 先停掉上一轮：重复点击发送时不能叠加两个计时器。
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
