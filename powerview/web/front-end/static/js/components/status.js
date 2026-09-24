export function createStatus() {
  const message = document.querySelector('#status-message');
  return {
    idle(text) { message.textContent = text; },
  };
}
